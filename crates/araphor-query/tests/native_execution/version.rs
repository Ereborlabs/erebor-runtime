use super::*;
use araphor_data::{ManagedInstance, ManagedRead};

pub(super) async fn execute(
    engine: &Arc<Engine>,
    definition: PreparedDefinition,
    target: &ManagedInstance,
    current: &ManagedInstance,
) -> TestResult<Arc<publication::Publication>> {
    let publication = publication::Publication::finite(
        engine,
        definition.plan().schema().inner().clone(),
        ManagedRead {
            instance: target.clone(),
            expected: (target != current).then(|| current.clone()),
            follow: false,
            rebuild: false,
            source: None,
            completed: None,
            execution: None,
        },
    );
    engine
        .session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            NOW,
        )?
        .run_managed(definition, publication.clone(), b"native-query")
        .await?;
    Ok(publication)
}

#[tokio::test]
async fn indexed_versions_keep_graph() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_contexts(&[super::graph::input(1)?])?;
    let definition = sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#);
    let (initial, _) = prepare(&engine, &super::graph::image()?, &definition).await?;
    let control = AnalysisReadControl::default();
    let admitted = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    let first = execute(&engine, initial.clone(), &admitted, &admitted).await?;
    let links = super::graph::links(&store)?;
    assert_eq!(links.len(), 3);
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    let mut changed = definition.clone();
    changed.description = "Updated metadata".into();
    let (definition, spec) = specification(&engine, &super::graph::image()?, &changed).await?;
    let candidate = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let next = execute(&engine, definition, &candidate, &current).await?;
    assert_eq!(super::graph::links(&store)?, links);
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("switched")?;
    assert_eq!(current.generation, candidate.generation);
    let rollback = store.prepare_managed_version(&current, &admitted.spec, || Ok(()))?;
    let restored = execute(&engine, initial, &rollback, &current).await?;
    assert_eq!(super::graph::links(&store)?, links);
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("rollback")?;
    assert_eq!(current.generation, admitted.generation);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .is_none());
    drop((first, next, restored, engine, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(super::graph::links(&store)?, links);
    assert_eq!(
        store.managed_instance(TENANT, "native-query", &control)?,
        Some(current)
    );
    Ok(())
}

#[tokio::test]
async fn finite_versions_preserve_consumers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    let definition = sql(
        r#"SELECT * FROM "native-fixture"."1".copy(input => (SELECT source_cursor AS value FROM events))"#,
    );
    let (initial, _) = prepare(&engine, &image()?, &definition).await?;
    event(&store, TENANT, 1)?;
    let control = AnalysisReadControl::default();
    let admitted = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    let first = execute(&engine, initial.clone(), &admitted, &admitted).await?;
    assert_eq!(values(&first.selected())?, vec![1]);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .is_none());
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    event(&store, TENANT, 2)?;
    let mut changed = definition.clone();
    changed.description = "Updated metadata".into();
    let (definition, spec) = specification(&engine, &image()?, &changed).await?;
    let candidate = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let next = execute(&engine, definition, &candidate, &current).await?;
    assert_eq!(values(&next.selected())?, vec![1, 2]);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .is_none());
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("switched")?;
    assert_eq!(current.generation, candidate.generation);
    let rollback = store.prepare_managed_version(&current, &admitted.spec, || Ok(()))?;
    assert_eq!(rollback.generation, admitted.generation);
    let restored = execute(&engine, initial, &rollback, &current).await?;
    assert_eq!(values(&restored.selected())?, vec![1, 2]);
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("rollback")?;
    assert_eq!(current.generation, admitted.generation);
    assert_eq!(current.progress, restored.receipt().commit_revision);
    drop((first, next, restored, engine, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_instance(TENANT, "native-query", &control)?,
        Some(current)
    );
    Ok(())
}

#[tokio::test]
async fn finite_keeps_saved_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    let (definition, publication) = prepare(&engine, &image()?, &sql(r#"SELECT * FROM "native-fixture"."1".copy(input => (SELECT source_cursor AS value FROM events))"#)).await?;
    let mut stream = subscribe(&engine, definition.clone(), publication.clone())?;
    let first = next(&mut stream).await?;
    publication.assert_consumed(first.cursor.position())?;
    stream.cancel_and_join().await?;
    let control = AnalysisReadControl::default();
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    event(&store, TENANT, 2)?;
    let once = execute(&engine, definition.clone(), &current, &current).await?;
    assert_eq!(values(&once.selected())?, vec![1, 2]);
    publication.assert_consumed(first.cursor.position())?;
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let followed = next(&mut stream).await?;
    assert_eq!(values(&publication.selected())?, vec![1, 2]);
    publication.assert_consumed(followed.cursor.position())?;
    stream.cancel_and_join().await?;
    drop((first, followed, publication, once, engine, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_history(
                &AnalysisSelectionV1::tenant(TENANT),
                "native-query",
                &control
            )?
            .len(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn tokenless_follow_consumes_replay() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_contexts(&[super::graph::input(1)?])?;
    let (definition, _) = prepare(
        &engine,
        &super::graph::image()?,
        &sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#),
    )
    .await?;
    let current = store
        .managed_instance(TENANT, "native-query", &AnalysisReadControl::default())?
        .ok_or("instance")?;
    let finite = execute(&engine, definition.clone(), &current, &current).await?;
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .is_none());
    event(&store, TENANT, 2)?;
    store.commit_contexts(&[super::graph::input(2)?])?;
    let publication =
        publication::Publication::new(&engine, definition.plan().schema().inner().clone());
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let first = next(&mut stream).await?;
    publication.assert_consumed(first.cursor.position())?;
    let (&call, returned) = first.calls.first_key_value().ok_or("call")?;
    assert_eq!(
        returned.changes().ok_or("changes")?.base.as_ref(),
        finite.receipt().results.get(&call)
    );
    for name in ["affected", "after"] {
        assert_eq!(
            returned
                .evaluation()
                .inputs
                .iter()
                .find(|input| input.data.name == name)
                .ok_or("changed input")?
                .data
                .rows(),
            1
        );
    }
    assert_eq!(super::graph::links(&store)?.len(), 6);
    stream.cancel_and_join().await?;
    let consumed = first.cursor.position();
    drop((first, finite, publication, engine, store));
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    let (definition, _) = specification(
        &engine,
        &super::graph::image()?,
        &sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#),
    )
    .await?;
    let publication =
        publication::Publication::new(&engine, definition.plan().schema().inner().clone());
    publication.assert_consumed(consumed)?;
    event(&store, TENANT, 3)?;
    store.commit_contexts(&[super::graph::input(3)?])?;
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let resumed = next(&mut stream).await?;
    assert!(resumed.cursor.position() > consumed);
    publication.assert_consumed(resumed.cursor.position())?;
    assert_eq!(super::graph::links(&store)?.len(), 9);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn rollback_revives_saved_consumer() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_contexts(&[super::graph::input(1)?])?;
    let program = sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#);
    let (definition, publication) = prepare(&engine, &super::graph::image()?, &program).await?;
    let control = AnalysisReadControl::default();
    let mut stream = subscribe(&engine, definition.clone(), publication.clone())?;
    let first = next(&mut stream).await?;
    publication.assert_consumed(first.cursor.position())?;
    stream.cancel_and_join().await?;
    let original = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("instance")?;
    event(&store, TENANT, 2)?;
    store.commit_contexts(&[super::graph::input(2)?])?;
    let mut changed = program;
    changed.description = "Updated metadata".into();
    let (updated, spec) = specification(&engine, &super::graph::image()?, &changed).await?;
    let candidate = store.prepare_managed_version(&original, &spec, || Ok(()))?;
    execute(&engine, updated, &candidate, &original).await?;
    let current = store
        .managed_instance(TENANT, "native-query", &control)?
        .ok_or("switched")?;
    let rollback = store.prepare_managed_version(&current, &original.spec, || Ok(()))?;
    assert_eq!(rollback.generation, original.generation);
    let finite = execute(&engine, definition.clone(), &rollback, &current).await?;
    publication.assert_consumed(first.cursor.position())?;
    event(&store, TENANT, 3)?;
    store.commit_contexts(&[super::graph::input(3)?])?;
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let resumed = next(&mut stream).await?;
    let (&call, returned) = resumed.calls.first_key_value().ok_or("call")?;
    assert_eq!(
        returned.changes().ok_or("changes")?.base.as_ref(),
        finite.receipt().results.get(&call)
    );
    publication.assert_consumed(resumed.cursor.position())?;
    for name in ["affected", "after"] {
        assert_eq!(
            returned
                .evaluation()
                .inputs
                .iter()
                .find(|input| input.data.name == name)
                .ok_or("changed input")?
                .data
                .rows(),
            1
        );
    }
    assert_eq!(super::graph::links(&store)?.len(), 9);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn bootstrap_retries_keep_progress() -> TestResult {
    for stale in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
        let engine = Engine::new(store.clone(), Limits::default())?;
        event(&store, TENANT, 1)?;
        store.commit_contexts(&[super::graph::input(1)?])?;
        let (definition, publication) = prepare(
            &engine,
            &super::graph::image()?,
            &sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#),
        )
        .await?;
        let control = AnalysisReadControl::default();
        let current = store
            .managed_instance(TENANT, "native-query", &control)?
            .ok_or("instance")?;
        let finite = execute(&engine, definition.clone(), &current, &current).await?;
        let before = super::graph::links(&store)?;
        if stale {
            publication
                .stale
                .store(true, std::sync::atomic::Ordering::SeqCst);
        } else {
            publication
                .reject
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        event(&store, TENANT, 2)?;
        store.commit_contexts(&[super::graph::input(2)?])?;
        let mut stream = subscribe(&engine, definition.clone(), publication.clone())?;
        let error = next(&mut stream).await.err().ok_or("failed publication")?;
        stream.cancel_and_join().await?;
        publication.assert_consumed(araphor_data::StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        })?;
        assert_eq!(super::graph::links(&store)?, before);
        let session = engine.session(AnalysisSelectionV1::tenant(TENANT), &control, NOW)?;
        let session = if stale {
            let recovery = araphor_query::follow::SourceRecovery::take(error.as_ref())
                .ok_or("source recovery")?;
            let recovery =
                tokio::time::timeout(Duration::from_secs(10), recovery.changed(&control)).await??;
            recovery.resume(session, &definition)
        } else {
            publication.finish_cancelled()?;
            session
        };
        publication
            .later
            .store(3, std::sync::atomic::Ordering::SeqCst);
        let resume = store.managed_resume(TENANT, "native-query", &control)?;
        let mut stream = Subscription::managed(
            session,
            definition,
            publication.clone(),
            b"native-query",
            resume.frontier,
            Arc::new(SystemClock::default()),
        )?;
        let retried = next(&mut stream).await?;
        publication.assert_consumed(retried.cursor.position())?;
        assert_eq!(
            store
                .read_at(retried.cursor.position().commit_revision)?
                .source_receipt(&source(TENANT))?
                .ok_or("captured receipt")?
                .contiguous_cursor,
            2
        );
        assert_eq!(
            store
                .view()?
                .source_receipt(&source(TENANT))?
                .ok_or("current receipt")?
                .contiguous_cursor,
            3
        );
        let (&call, returned) = retried.calls.first_key_value().ok_or("call")?;
        assert_eq!(
            returned.changes().ok_or("changes")?.base.as_ref(),
            finite.receipt().results.get(&call)
        );
        for name in ["affected", "after"] {
            assert_eq!(
                returned
                    .evaluation()
                    .inputs
                    .iter()
                    .find(|input| input.data.name == name)
                    .ok_or("changed input")?
                    .data
                    .rows(),
                1
            );
        }
        assert_eq!(super::graph::links(&store)?.len(), 6);
        store.commit_contexts(&[super::graph::input(3)?])?;
        let later = next(&mut stream).await?;
        assert!(later.cursor.position() > retried.cursor.position());
        publication.assert_consumed(later.cursor.position())?;
        assert_eq!(super::graph::links(&store)?.len(), 9);
        stream.cancel_and_join().await?;
    }
    Ok(())
}
