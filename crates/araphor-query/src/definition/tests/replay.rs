use super::*;

use crate::definition::Invocation;

#[tokio::test]
async fn replay_uses_captured_inputs() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    fixture.event(1)?;
    fixture.event(2)?;
    let prepared = fixture.prepare(&Fixture::definition()).await?;
    let original = fixture.execute(&prepared, Invocation::default()).await?;
    let (&id, call) = original.calls.first_key_value().ok_or("original call")?;
    let evaluation = call.evaluation().clone();
    fixture.event(3)?;
    let mut newer = Fixture::bundle();
    newer.root.revision = "r2".into();
    newer.artifacts[0].descriptor.revision = "r2".into();
    let PackageImplementationV1::Sql { program, .. } = &mut newer.artifacts[0].implementations[0]
    else {
        return Err("SQL implementation absent".into());
    };
    program.outputs.insert("result".into(), "SELECT source.value + parameters.increment + CAST(100 AS BIGINT UNSIGNED) AS value FROM source CROSS JOIN parameters".into());
    fixture.install(&newer)?;
    let fresh = fixture.execute(&prepared, Invocation::default()).await?;
    assert_eq!(
        fresh
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        3
    );
    let session = fixture.engine.session(
        araphor_data::AnalysisSelectionV1::new([1; 16], Vec::new()),
        &AnalysisReadControl::default(),
        1,
    )?;
    let before = fixture.engine.store().meta()?;
    let replay = session
        .replay_call(&prepared, id, evaluation.clone())
        .await?;
    assert!(replay.snapshot.page.extraction.sources.is_empty());
    assert_eq!(replay.calls.len(), 1);
    let returned = &replay.calls[&id];
    assert_eq!(returned.evaluation().context, evaluation.context);
    assert_eq!(
        returned.evaluation().inputs[0].revision,
        evaluation.inputs[0].revision
    );
    assert_eq!(
        returned.evaluation().inputs[0].coverage,
        evaluation.inputs[0].coverage
    );
    assert_eq!(returned.output().evidence, call.output().evidence);
    let descriptor = &Fixture::bundle().artifacts[0].descriptor;
    assert_eq!(
        serde_json::to_value(sdk::wire::Output::encode(
            descriptor,
            returned.evaluation(),
            returned.output()
        )?)?,
        serde_json::to_value(sdk::wire::Output::encode(
            descriptor,
            call.evaluation(),
            call.output()
        )?)?
    );
    assert_eq!(prepared.resolved().images[0].image.revision, "r1");
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(session
        .replay_call(&prepared, u64::MAX, evaluation.clone())
        .await
        .is_err());
    let foreign = fixture.engine.session(
        araphor_data::AnalysisSelectionV1::tenant([2; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    assert!(foreign
        .replay_call(&prepared, id, evaluation.clone())
        .await
        .is_err());
    let mut invalid = evaluation;
    invalid.inputs.clear();
    assert!(session.replay_call(&prepared, id, invalid).await.is_err());
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((original, fresh, replay, prepared, session, foreign));
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    Ok(())
}
