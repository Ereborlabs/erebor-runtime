use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_keeps_pending_input() -> TestResult {
    for restart in [false, true] {
        let fixture = fixture().await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, held) = mpsc::channel();
        let state = Arc::new(SinkState {
            gate: Some(WriterGate {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(held),
            }),
            ..Default::default()
        });
        let definition = fixture
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
                    input => (SELECT source_cursor AS value FROM events),
                    mode => 'sum-input', amount => 0)"#,
            ))
            .await?;
        let calls = Fixture::calls(&definition.plan)?;
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        let call_id = call.id();
        let bundle = definition
            .images()
            .find(|bundle| {
                bundle.bundle().root == call.image().image && bundle.digest() == call.image().digest
            })
            .ok_or("managed call image")?;
        let implementation = bundle
            .bundle()
            .artifact(call.package())?
            .implementation(call.export())?;
        let declaration = araphor_data::ManagedCall {
            image: call.image().clone(),
            package: call.package().clone(),
            export: call.export().into(),
            target: implementation.target().into(),
            artifact: implementation.identity()?,
            arguments: call.arguments().to_vec(),
            dependencies: Default::default(),
        };
        let original = fixture.managed(&definition, AnalysisSelectionV1::tenant([1; 16]))?;
        let mut spec = original.spec.clone();
        spec.id = "graph-cut".into();
        spec.manifest.calls = [(call_id, declaration)].into_iter().collect();
        spec.destination = araphor_data::ManagedDestination::Graph {
            source: fixture.engine.store().source_page([1; 16], None)?[0].clone(),
            events_sql: "SELECT * FROM events".into(),
            calls: [call_id].into_iter().collect(),
            operation: araphor_data::ManagedGraphOperation::Evaluate,
        };
        let selection = spec.destination.selection(&original.grant.selection)?;
        let admitted = fixture
            .engine
            .store()
            .admit_managed(&spec, &original.grant, || Ok(()))?;
        let instance = fixture.engine.store().set_managed_running(
            spec.tenant,
            &spec.id,
            admitted.lifecycle,
            true,
            || Ok(()),
        )?;
        let target = Arc::new(Sink {
            schema: Arc::clone(definition.plan.schema().inner()),
            calls,
            state: Arc::clone(&state),
            managed: Some(instance),
        });
        let mut subscription = Subscription::managed(
            fixture
                .engine
                .session(selection.clone(), &AnalysisReadControl::default(), 0)?,
            definition.clone(),
            Arc::clone(&target) as Arc<dyn ManagedPublication>,
            b"managed-test",
            None,
            Arc::new(SystemClock::default()),
        )?;
        let mut next = Box::pin(subscription.next());
        tokio::select! {
            result = &mut next => return Err(format!("publication gate bypassed: {result:?}").into()),
            observed = observed => observed?,
        }
        let frontier = state.frontier.lock().unwrap().clone().ok_or("input cut")?;
        let captured = crate::follow::Cursor::decode(&frontier.cursor)?.read_revision();
        fixture.event(2)?;
        let arrival = fixture.engine.store().meta()?.commit_revision;
        fixture.context(1)?;
        let published = fixture.engine.store().meta()?.commit_revision;
        assert!(captured < arrival && arrival < published);
        state.publication.store(published, Ordering::SeqCst);
        release.send(())?;
        let first = next.await.ok_or("captured receipt")??;
        assert!(first.snapshot.managed().unwrap().follows_graph());
        assert_eq!(
            first.snapshot.page.extraction.meta.commit_revision,
            captured
        );
        assert_eq!(first.cursor.read_revision(), published);
        assert_eq!(
            first.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            1
        );
        drop(first);
        if restart {
            subscription.cancel_and_join().await?;
            subscription = Subscription::managed(
                fixture
                    .engine
                    .session(selection.clone(), &AnalysisReadControl::default(), 0)?,
                definition.clone(),
                Arc::clone(&target) as Arc<dyn ManagedPublication>,
                b"managed-test",
                Some(frontier),
                Arc::new(SystemClock::default()),
            )?;
        }
        release.send(())?;
        let update = tokio::time::timeout(Duration::from_secs(30), subscription.next())
            .await?
            .ok_or("pending input receipt")??;
        assert_eq!(
            update.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            2
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 2);
        let now = update.evaluated_utc_ns + 1;
        let frontier = state
            .frontier
            .lock()
            .unwrap()
            .clone()
            .ok_or("caught-up cut")?;
        drop(update);
        subscription.cancel_and_join().await?;
        let (idle, observed) = tokio::sync::oneshot::channel();
        let mut resumed = Subscription::managed(
            fixture
                .engine
                .session(selection, &AnalysisReadControl::default(), 0)?,
            definition,
            target,
            b"managed-test",
            Some(frontier),
            ResumeClock::new(now, Some(idle)),
        )?;
        let mut next = Box::pin(resumed.next());
        tokio::select! {
            biased;
            result = &mut next => return Err(format!("caught-up input executed again: {result:?}").into()),
            observed = observed => observed?,
        }
        assert_eq!(state.commits.load(Ordering::SeqCst), 2);
        assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
        drop(next);
        resumed.cancel_and_join().await?;
        drop(state.receipt.lock().unwrap().take());
        released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn managed_mode_must_match() -> TestResult {
    for follow in [false, true] {
        let fixture = fixture().await?;
        let state = Arc::new(SinkState::default());
        state.finite.store(follow, Ordering::SeqCst);
        let (definition, target) = prepared(&fixture, &state).await?;
        let control = AnalysisReadControl::default();
        let error = if follow {
            let mut subscription = stream(&fixture, definition, target, &control)?;
            let error = subscription
                .next()
                .await
                .ok_or("mode rejection")?
                .unwrap_err();
            subscription.cancel_and_join().await?;
            error
        } else {
            Subscription::managed_once(
                fixture
                    .engine
                    .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?,
                definition,
                target,
                b"managed-test",
                NOW,
            )
            .await
            .unwrap_err()
        };
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
        assert_eq!(state.admissions.load(Ordering::SeqCst), 0);
        assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
        released(&fixture)?;
    }
    Ok(())
}
