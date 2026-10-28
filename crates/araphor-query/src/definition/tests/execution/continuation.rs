use super::*;

async fn continues(target: &str) -> TestResult {
    let fixture = Fixture::installed(&component(target, "continue-input")?)?;
    let before = fixture.engine.store().meta()?;
    let mut state = invocation("initial");
    let mut saved = None;
    for (value, expected) in [(2, 2), (3, 5)] {
        let prepared = fixture
            .prepare(&Fixture::sql(format!(
                r#"SELECT * FROM "runtime-fixture"."1"."continue-input"(
                input => (SELECT CAST({value} AS BIGINT UNSIGNED) AS value))"#,
            )))
            .await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        if let Some(previous) = &saved {
            let previous: &Arc<CallResult> = previous;
            state.checkpoints.insert(
                id,
                previous
                    .output()
                    .checkpoint
                    .clone()
                    .ok_or("saved checkpoint")?,
            );
            state
                .previous_outputs
                .insert(id, previous.output().datasets.clone());
        }
        let output = fixture.execute(&prepared, state.clone()).await?;
        assert_eq!(values(&output.batches)?, [expected], "{target}");
        let call = Arc::clone(output.calls.get(&id).ok_or("returned call")?);
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [value]);
        if let Some(previous) = &saved {
            assert_eq!(
                values(&call.evaluation().previous_outputs[0].batches)?,
                values(&previous.output().datasets[0].batches)?
            );
        } else {
            assert!(call.evaluation().previous_outputs.is_empty());
        }
        saved = Some(call);
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(fixture);
    let saved = saved.ok_or("saved output")?;
    assert_eq!(
        values(&saved.evaluation().previous_outputs[0].batches)?,
        [2]
    );
    assert_eq!(values(&saved.output().datasets[0].batches)?, [5]);
    Ok(())
}

#[tokio::test]
async fn sql_previous_outputs() -> TestResult {
    continues("sql").await
}

#[tokio::test]
async fn wasm_previous_outputs() -> TestResult {
    continues("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native runtime fixture"]
async fn native_previous_outputs() -> TestResult {
    continues("native").await
}

#[tokio::test]
async fn previous_state_preflight() -> TestResult {
    let fixture = Fixture::installed(&component("sql", "continue-input")?)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."continue-input"(
            input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        ))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let mut previous = checkpoint(2)?.datasets.remove(0);
    previous.name = "data".into();
    let mut state = invocation("state");
    state.previous_outputs.insert(id, vec![previous.clone()]);
    assert!(fixture.execute(&prepared, state.clone()).await.is_err());
    state.checkpoints.insert(id, checkpoint(2)?);
    assert_eq!(
        values(&fixture.execute(&prepared, state.clone()).await?.batches)?,
        [5]
    );
    state.previous_outputs.insert(id + 1, vec![previous]);
    assert!(fixture.execute(&prepared, state.clone()).await.is_err());
    state.previous_outputs.remove(&(id + 1));
    state.previous_outputs.get_mut(&id).ok_or("prior data")?[0].name = "foreign".into();
    assert!(fixture.execute(&prepared, state.clone()).await.is_err());
    state.previous_outputs.clear();
    assert!(fixture.execute(&prepared, state).await.is_err());
    Ok(())
}

#[tokio::test]
async fn previous_outputs_not_evidence() -> TestResult {
    let mut bundle = component("sql", "continue-input")?;
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL implementation".into());
    };
    program.evidence = Some(
        "SELECT 'data' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, \
            'previous_data' AS input_dataset, __row_index AS input_row FROM previous_data"
            .into(),
    );
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."continue-input"(
            input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        ))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let mut previous = checkpoint(2)?.datasets.remove(0);
    previous.name = "data".into();
    let mut state = invocation("no-prior-evidence");
    state.checkpoints.insert(id, checkpoint(2)?);
    state.previous_outputs.insert(id, vec![previous]);
    assert!(fixture.execute(&prepared, state).await.is_err());
    Ok(())
}
