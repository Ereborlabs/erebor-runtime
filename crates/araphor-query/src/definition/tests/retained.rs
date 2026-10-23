use super::*;
use crate::definition::Invocation;

#[tokio::test]
async fn retained_images_use_plans() -> TestResult {
    let package = Fixture::bundle();
    let fixture = Fixture::installed(&package)?;
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
    );
    let original = fixture.prepare(&definition).await?;
    let resolved = original.resolved().clone();
    fixture
        .engine
        .store()
        .admit_definition([1; 16], &resolved, || Ok(()))?;
    let pin = resolved.images[0].clone();
    fixture
        .engine
        .store()
        .uninstall_package_image([1; 16], &pin, || Ok(()))?;
    let before = fixture.engine.store().meta()?;
    assert!(fixture.prepare(&definition).await.is_err());
    let control = AnalysisReadControl::default();
    let session = fixture.engine.session(
        araphor_data::AnalysisSelectionV1::tenant([1; 16]),
        &control,
        1,
    )?;
    let retained = session.prepare_resolved(&resolved).await?;
    assert_eq!(retained.resolved(), &resolved);
    assert_eq!(
        retained.plan.display_indent_schema().to_string(),
        original.plan.display_indent_schema().to_string()
    );
    let original_calls = Fixture::calls(&original.plan)?;
    let retained_calls = Fixture::calls(&retained.plan)?;
    assert_eq!(original_calls.len(), 1);
    assert_eq!(retained_calls.len(), 1);
    assert_ne!(retained_calls[0], original_calls[0]);
    assert_eq!(retained_calls[0].id(), original_calls[0].id());
    assert_eq!(retained_calls[0].image(), original_calls[0].image());
    assert_eq!(retained_calls[0].package(), original_calls[0].package());
    assert_eq!(retained_calls[0].export(), original_calls[0].export());
    assert_eq!(retained_calls[0].output(), original_calls[0].output());
    assert_eq!(
        retained_calls[0].descriptor(),
        original_calls[0].descriptor()
    );
    assert_eq!(retained_calls[0].arguments(), original_calls[0].arguments());
    let output = session
        .execute_definition(&retained, Invocation::default())
        .await?;
    assert_eq!(output.calls.len(), 1);
    let (&id, returned) = output
        .calls
        .first_key_value()
        .ok_or("native retained call")?;
    assert!(returned.belongs_to(&retained_calls[0]));
    assert!(!returned.belongs_to(&original_calls[0]));
    assert_eq!(returned.evaluation().inputs[0].data.rows(), 1);
    let values = output
        .batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .into_iter()
                .flat_map(|array| array.values().iter().copied())
        })
        .collect::<Vec<_>>();
    assert_eq!(values, vec![9]);
    let replay = session
        .replay_call(&retained, id, returned.evaluation().clone())
        .await?;
    let replayed = &replay.calls[&id];
    let descriptor = &package.artifacts[0].descriptor;
    assert_eq!(
        sdk::wire::Output::encode(descriptor, replayed.evaluation(), replayed.output())?,
        sdk::wire::Output::encode(descriptor, returned.evaluation(), returned.output())?
    );
    let mut forged = resolved.clone();
    forged
        .definition
        .labels
        .insert("new".into(), "definition".into());
    assert!(session.prepare_resolved(&forged).await.is_err());
    let foreign = fixture.engine.session(
        araphor_data::AnalysisSelectionV1::tenant([2; 16]),
        &control,
        1,
    )?;
    assert!(foreign.prepare_resolved(&resolved).await.is_err());
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((
        output,
        replay,
        retained,
        original,
        session,
        foreign,
        original_calls,
        retained_calls,
    ));
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    Ok(())
}
