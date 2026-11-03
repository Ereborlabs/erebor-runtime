use super::*;

use crate::definition::Invocation;

#[tokio::test]
async fn replay_uses_journal_cut() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    fixture.event(1)?;
    fixture.event(2)?;
    let mut prepared = fixture.prepare(&Fixture::definition()).await?;
    let control = AnalysisReadControl::default();
    let selection = araphor_data::AnalysisSelectionV1::tenant([1; 16]);
    let instance = fixture.managed(&mut prepared, selection.clone())?;
    let session = fixture.engine.session(selection, &control, 1)?;
    let captured = session
        .capture_managed(
            &prepared,
            Invocation::default(),
            araphor_data::ManagedRead {
                instance: instance.clone(),
                source: None,
                execution: None,
                follow: false,
                expected: None,
                rebuild: false,
                completed: None,
            },
        )
        .await?;
    let attempt = fixture.engine.store().register_managed_attempt(
        captured.snapshot().managed().ok_or("managed capture")?,
        &araphor_data::ManagedRequest {
            id: "package-call".into(),
            time_utc_ns: 1,
            seed: None,
            rebuild: false,
            witness_expiry: u64::MAX,
            frontier: None,
        },
        || Ok(()),
    )?;
    let original = captured.execute().await?;
    let returns = original
        .calls
        .iter()
        .map(|(id, call)| araphor_data::ManagedReturn {
            call: *id,
            evaluation: call.evaluation(),
            output: call.output(),
            changes: call.changes(),
        })
        .collect::<Vec<_>>();
    let receipt = fixture.engine.store().commit_managed(
        &araphor_data::ManagedCommit {
            attempt: &attempt,
            completed: true,
            now_utc_ns: 1,
            returns: &returns,
            selected: &sdk::Dataset {
                name: "selected".into(),
                batches: original.batches.clone(),
            },
            selected_schema: prepared.plan.schema().as_arrow(),
        },
        || Ok(()),
    )?;
    let (&id, call) = original.calls.first_key_value().ok_or("original call")?;
    let evaluation = call.evaluation().clone();
    let (reference, saved, _) = fixture.engine.store().managed_reference(
        &instance,
        &receipt.results[&id].result_id,
        1,
        &control,
    )?;
    assert_eq!(saved, Some(id));
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
    let before = fixture.engine.store().meta()?;
    let replay = session
        .replay_reference(&prepared, &reference, Some(id))
        .await?;
    assert_eq!(
        replay.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
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
        sdk::wire::Output::encode(descriptor, returned.evaluation(), returned.output())?,
        sdk::wire::Output::encode(descriptor, call.evaluation(), call.output())?
    );
    assert_eq!(prepared.resolved().images[0].image.revision, "r1");
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(session
        .replay_reference(&prepared, &reference, Some(u64::MAX))
        .await
        .is_err());
    let foreign = fixture.engine.session(
        araphor_data::AnalysisSelectionV1::tenant([2; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    assert!(foreign
        .replay_reference(&prepared, &reference, Some(id))
        .await
        .is_err());
    assert!(session
        .replay_reference(&prepared, &attempt, Some(id))
        .await
        .is_err());
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((
        original, fresh, replay, prepared, session, foreign, evaluation,
    ));
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    Ok(())
}
