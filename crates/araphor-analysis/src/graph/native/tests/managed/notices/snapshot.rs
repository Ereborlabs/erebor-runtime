use super::*;
use crate::graph::native::tests::feed::append;
use crate::graph::tests::fixture::wire;
use futures_util::FutureExt as _;

#[tokio::test]
async fn manifest_replacement_rebinds() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let bytes = Vec::<u8>::try_from(&wire(
        4,
        erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
        2,
        2,
        [20; 16],
    ))?;
    let fourth = araphor_data::DiscoveryRecordV1::try_from((
        araphor_data::DiscoveryRecordIdV1 {
            durable_cursor: 4,
            ..fixture
                .records
                .first()
                .ok_or("Graph record fixture")?
                .id
                .clone()
        },
        bytes.as_slice(),
    ))?;
    assert_eq!(fourth.id.stream, fixture.source);
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "manifest-replacement",
            "SELECT * FROM events",
        )
        .await?;
    let mut receipt = job.run(request("seed")?, &fixture.control).await?;
    let (plan, sources) = fixture
        .query
        .prepare(
            "SELECT graph_result_id, snapshot, commit_revision FROM graph_manifest",
            Vec::new(),
        )
        .await?;
    let control = AnalysisReadControl::default();
    let session = fixture.query.session(
        AnalysisSelectionV1::tenant(fixture.source.tenant_id),
        &control,
        request("manifest-time")?.time_utc_ns,
    )?;
    let mut stream = session.subscribe(plan, sources, b"replacement Graph manifest", true)?;
    let outcome = std::panic::AssertUnwindSafe(async {
        let mut original = None::<(String, u64, araphor_data::GraphSnapshotV1)>;
        for last in [3, 4] {
            if last == 4 {
                append(&fixture.query, &fixture.source, &fourth, 4)?;
                receipt = job.run(request("replacement")?, &fixture.control).await?;
            }
            assert_eq!(receipt.results.len(), 3);
            let update = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    let update = stream.next().await.ok_or("Graph manifest ended")??;
                    if update.batches.is_some() {
                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(update);
                    }
                }
            })
            .await??;
            assert_eq!(update.operation, araphor_query::follow::Operation::Replace);
            let batches = update.batches.as_ref().ok_or("Graph manifest rows")?;
            assert_eq!(
                batches
                    .iter()
                    .map(sdk::RecordBatch::num_rows)
                    .sum::<usize>(),
                1
            );
            let batch = batches
                .iter()
                .find(|batch| batch.num_rows() != 0)
                .ok_or("Graph manifest row")?;
            let id = batch
                .column_by_name("graph_result_id")
                .and_then(|column| {
                    column
                        .as_any()
                        .downcast_ref::<sdk::arrow_array::StringArray>()
                })
                .ok_or("Graph manifest ID")?
                .value(0)
                .to_owned();
            let revision = batch
                .column_by_name("commit_revision")
                .and_then(|column| {
                    column
                        .as_any()
                        .downcast_ref::<sdk::arrow_array::UInt64Array>()
                })
                .ok_or("Graph manifest revision")?
                .value(0);
            let snapshot = batch
                .column_by_name("snapshot")
                .and_then(|column| {
                    column
                        .as_any()
                        .downcast_ref::<sdk::arrow_array::BinaryArray>()
                })
                .ok_or("Graph manifest snapshot")?;
            let graph: araphor_data::GraphSnapshotV1 = serde_json::from_slice(snapshot.value(0))?;
            let head = fixture
                .query
                .store()
                .processor_result(&fixture.graph_scope())?
                .ok_or("Graph manifest head")?;
            assert_eq!(id, head.result_id);
            assert_eq!(revision, receipt.commit_revision);
            assert_eq!(revision, head.commit_revision);
            assert!(update.cursor.read_revision() >= revision);
            assert_eq!(graph.scope.identity, fixture.source);
            assert_eq!((graph.first_cursor, graph.last_cursor), (1, last));
            let mut evidence = fixture
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect::<Vec<_>>();
            if last == 4 {
                evidence.push(fourth.id.clone());
            }
            evidence.sort();
            assert_eq!(graph.input_manifest.evidence, evidence);
            assert!(update
                .snapshot
                .results()
                .any(|result| result.result_id == id && result.commit_revision == revision));
            if let Some((previous_id, previous_revision, previous)) = &original {
                assert_ne!(&id, previous_id);
                assert!(revision > *previous_revision);
                assert_eq!(graph.previous_result_id.as_ref(), Some(previous_id));
                assert_eq!(
                    fixture
                        .query
                        .store()
                        .graph_result(fixture.source.tenant_id, previous_id)?,
                    Some(previous.clone())
                );
            } else {
                assert!(graph.previous_result_id.is_none());
                original = Some((id, revision, graph));
            }
            drop(update);
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .catch_unwind()
    .await;
    let joined = stream.cancel_and_join().await;
    match outcome {
        Ok(outcome) => outcome?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    joined?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_publishes_snapshot() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let bytes = Vec::<u8>::try_from(&wire(
        4,
        erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
        2,
        2,
        [20; 16],
    ))?;
    let fourth = araphor_data::DiscoveryRecordV1::try_from((
        araphor_data::DiscoveryRecordIdV1 {
            durable_cursor: 4,
            ..fixture
                .records
                .first()
                .ok_or("Graph record fixture")?
                .id
                .clone()
        },
        bytes.as_slice(),
    ))?;
    assert_eq!(fourth.id.stream, fixture.source);
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "captured-prefix",
            "SELECT events.* FROM events CROSS JOIN graph_state
             WHERE source_cursor > consumed_cursor",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let (entered, release) = fixture.hold_facts();
    let running = tokio::spawn(async move {
        let receipt = next_receipt(&mut stream).await;
        (stream, receipt)
    });
    let changed: TestResult = async {
        tokio::task::spawn_blocking(move || {
            entered.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await??;
        append(&fixture.query, &fixture.source, &fourth, 4)?;
        release.send(())?;
        Ok(())
    }
    .await;
    drop(release);
    let (mut stream, first) = running.await?;
    let outcome: TestResult = async {
        changed?;
        let first = first?;
        assert_eq!(first.results.len(), 3);
        let heads = fixture.retained_heads()?;
        assert_eq!(heads.len(), 1);
        let (first_id, first_graph, revision) = &heads[0];
        assert_eq!(*revision, first.commit_revision);
        assert_eq!((first_graph.first_cursor, first_graph.last_cursor), (1, 3));
        assert_eq!(
            first_graph.input_manifest.evidence,
            fixture
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect::<Vec<_>>()
        );
        let health = fixture
            .query
            .store()
            .processor_health(&fixture.graph_scope())?
            .ok_or("prefix progress")?;
        assert_eq!((health.consumed_cursor, health.accepted_cursor), (3, 4));
        let second = next_receipt(&mut stream).await?;
        assert_eq!(second.results.len(), 3);
        assert!(second.commit_revision > first.commit_revision);
        let head = fixture
            .query
            .store()
            .processor_result(&fixture.graph_scope())?
            .ok_or("catch-up head")?;
        assert_eq!(head.commit_revision, second.commit_revision);
        let graph = fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &head.result_id)?
            .ok_or("catch-up Graph")?;
        assert_eq!((graph.first_cursor, graph.last_cursor), (4, 4));
        assert_eq!(
            graph.input_manifest.evidence.as_slice(),
            std::slice::from_ref(&fourth.id)
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, first_id)?,
            Some(first_graph.clone())
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
        let empty = next_receipt(&mut stream).await?;
        assert!(empty.results.is_empty());
        assert!(empty.commit_revision > second.commit_revision);
        assert_eq!(
            fixture
                .query
                .store()
                .processor_result(&fixture.graph_scope())?,
            Some(head.clone())
        );
        let health = fixture
            .query
            .store()
            .processor_health(&fixture.graph_scope())?
            .ok_or("settled progress")?;
        assert_eq!((health.consumed_cursor, health.accepted_cursor), (4, 4));
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
        let before = fixture.query.store().meta()?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(
            fixture
                .query
                .store()
                .processor_result(&fixture.graph_scope())?,
            Some(head)
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
        Ok(())
    }
    .await;
    let joined = stream.cancel_and_join(&fixture.control).await;
    outcome?;
    joined?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finite_running_keeps_fence() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let bytes = Vec::<u8>::try_from(&wire(
        4,
        erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
        2,
        2,
        [20; 16],
    ))?;
    let fourth = araphor_data::DiscoveryRecordV1::try_from((
        araphor_data::DiscoveryRecordIdV1 {
            durable_cursor: 4,
            ..fixture
                .records
                .first()
                .ok_or("Graph record fixture")?
                .id
                .clone()
        },
        bytes.as_slice(),
    ))?;
    assert_eq!(fourth.id.stream, fixture.source);
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "finite-running",
            "SELECT * FROM events",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let input = request("finite-captured-prefix")?;
    let (entered, release) = fixture.hold_facts();
    let executing = Arc::clone(&job);
    let control = Arc::clone(&fixture.control);
    let offered = input.clone();
    let running = tokio::spawn(async move { executing.run(offered, &control).await });
    let changed: TestResult = async {
        tokio::task::spawn_blocking(move || {
            entered.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await??;
        append(&fixture.query, &fixture.source, &fourth, 4)?;
        release.send(())?;
        Ok(())
    }
    .await;
    drop(release);
    let failed = running.await?;
    changed?;
    assert!(failed.is_err());
    let data = fixture.query.store();
    let saved = data
        .managed_attempt(
            fixture.source.tenant_id,
            "finite-running",
            &input.id,
            &fixture.control,
        )?
        .ok_or("finite attempt")?;
    assert_eq!(
        saved.terminal().ok_or("finite terminal")?.exit,
        araphor_data::ManagedExit::Failed(Code::Conflict)
    );
    assert!(saved.receipt().is_none());
    assert!(data.processor_result(&fixture.graph_scope())?.is_none());
    assert!(fixture.retained_heads()?.is_empty());
    let current = data
        .managed_instance(fixture.source.tenant_id, "finite-running", &fixture.control)?
        .ok_or("finite current instance")?;
    assert!(current.running);
    assert_eq!(current.lifecycle, job.admitted().lifecycle);
    assert_eq!(current.progress, 0);
    let health = data
        .processor_health(&fixture.graph_scope())?
        .ok_or("finite source progress")?;
    assert_eq!((health.consumed_cursor, health.accepted_cursor), (0, 4));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notice_keeps_pending_signal() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let seed = fixture
        .managed_graph(&grant, &definition, "pending-seed", "SELECT * FROM events")
        .await?;
    let seeded = seed.run(request("seed")?, &fixture.control).await?;
    assert_eq!(seeded.results.len(), 3);
    let (id, graph, revision) = fixture
        .retained_heads()?
        .into_iter()
        .next()
        .ok_or("seeded Graph")?;
    assert_eq!(revision, seeded.commit_revision);
    assert_eq!((graph.first_cursor, graph.last_cursor), (1, 3));
    let scope = fixture.graph_scope();
    let head = fixture.query.store().processor_result(&scope)?;
    let evidence = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?;
    let job = fixture
        .managed_graph(&grant, &definition, "pending-notice", NOTICE_WORK_SQL)
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let outcome = std::panic::AssertUnwindSafe(async {
        let idle = next_receipt(&mut stream).await?;
        assert!(idle.results.is_empty());
        let signal = fixture.signal_notice(1)?;
        let (entered, release) = fixture.hold_facts();
        let (first, arrived) = tokio::join!(next_receipt(&mut stream), async {
            tokio::task::spawn_blocking(move || {
                entered.recv_timeout(std::time::Duration::from_secs(30))
            })
            .await??;
            let arrived = fixture.signal_notice(2)?;
            release.send(())?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(arrived)
        });
        let arrived = arrived?;
        let first = first?;
        assert_eq!(first.results.len(), 3);
        let captured = captured_revision(&first)?;
        assert!(signal <= captured);
        assert!(captured < arrived && arrived < first.commit_revision);
        let coverage = fixture
            .query
            .store()
            .source_receipt(&fixture.source)?
            .ok_or("notice source")?
            .coverage_revision;
        assert_eq!(
            fixture.query.store().graph_notice(&scope, &id, revision)?,
            Some((captured, coverage))
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
        let second = next_receipt(&mut stream).await?;
        assert_eq!(second.results.len(), 3);
        assert!(second.commit_revision > first.commit_revision);
        let captured = captured_revision(&second)?;
        assert!(captured >= arrived && captured < second.commit_revision);
        assert_eq!(
            fixture.query.store().graph_notice(&scope, &id, revision)?,
            Some((captured, coverage))
        );
        assert_eq!(fixture.query.store().processor_result(&scope)?, head);
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &id)?,
            Some(graph.clone())
        );
        assert_eq!(
            fixture
                .query
                .store()
                .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?,
            evidence
        );
        assert_eq!(
            fixture
                .query
                .store()
                .processor_health(&scope)?
                .ok_or("notice progress")?
                .consumed_cursor,
            3
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            fixture.query.store().managed_history(
                &grant.selection,
                "pending-notice",
                &fixture.control
            )?,
            [idle, first, second]
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .catch_unwind()
    .await;
    let joined = stream.cancel_and_join(&fixture.control).await;
    match outcome {
        Ok(outcome) => outcome?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    joined?;
    Ok(())
}
