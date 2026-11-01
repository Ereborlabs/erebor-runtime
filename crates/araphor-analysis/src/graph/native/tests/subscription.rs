use araphor_analysis_builtins::graph as algorithm;
use futures_util::StreamExt as _;

use super::*;

#[tokio::test]
async fn drains_captured_backlog() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture
        .prepare("WHERE source_cursor <= (SELECT consumed_cursor + 1 FROM graph_state)")
        .await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "graph-backlog",
            "SELECT * FROM events WHERE source_cursor <= (SELECT consumed_cursor + 1 FROM graph_state)",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let projection = &job.graph_owner().ok_or("Running Graph owner")?.projection;
    let observed = projection.observe_capture();
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let checked: TestResult = async {
        let mut previous = None;
        let mut previous_calls = std::collections::BTreeMap::<
            u64,
            std::collections::BTreeSet<araphor_data::DiscoveryRecordIdV1>,
        >::new();
        for consumed in 1..=3 {
            let receipt = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
                .await?
                .ok_or("Graph subscription ended")??;
            let scope = araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: fixture.source.clone(),
            };
            let head = fixture
                .query
                .store()
                .processor_result(&scope)?
                .ok_or("Graph processor result")?;
            let id = head.result_id;
            assert_eq!(head.commit_revision, receipt.commit_revision);
            let graph = fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &id)?
                .ok_or("Graph result")?;
            assert_eq!(graph.last_cursor, consumed);
            assert_eq!(graph.previous_result_id, previous);
            let health = fixture
                .query
                .store()
                .processor_health(&graph.scope)?
                .ok_or("Graph progress")?;
            assert_eq!(health.consumed_cursor, consumed);
            assert_eq!(health.accepted_cursor, 3);
            assert_eq!(
                fixture
                    .query
                    .store()
                    .processor_result(&graph.scope)?
                    .ok_or("Graph processor result")?
                    .result_id,
                id
            );
            let headers = fixture
                .query
                .store()
                .graph_window_headers(&fixture.source, None)?;
            let (result, _, revision) = headers
                .iter()
                .find(|(result, _, _)| result == &id)
                .ok_or("Graph backlog window")?;
            assert_eq!(result, &id);
            assert_eq!(*revision, receipt.commit_revision);
            assert!(receipt.commit_revision > 0);
            let captured = observed.try_recv()?;
            assert_eq!(captured.accepted, 3);
            assert_eq!(captured.consumed, consumed - 1);
            assert!(captured.source.upgrade().is_none());
            assert_eq!(receipt.results.len(), 3);
            for (&call, reference) in &receipt.results {
                let package = job
                    .graph_owner()
                    .ok_or("running Graph owner")?
                    .calls
                    .get(&call)
                    .ok_or("Graph package call")?
                    .descriptor();
                let detector = algorithm::Detector::from_id(&package.id)?;
                let evaluation_replay = fixture
                    .replay_result(job.admitted(), &reference.result_id, &fixture.control)
                    .await?;
                let evaluation = evaluation_replay
                    .calls
                    .values()
                    .next()
                    .ok_or("replayed Graph call")?
                    .evaluation();
                let records = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
                let units = algorithm::Unit::decode(&evaluation.input("units")?.data)?;
                let removals = algorithm::Unit::decode(&evaluation.input("unit_removals")?.data)?;
                let model = &package.exports[0];
                assert_eq!(
                    model
                        .change_inputs
                        .as_ref()
                        .ok_or("change contract")?
                        .is_reset(evaluation)?,
                    consumed == 1
                );
                assert!(evaluation.checkpoint.is_none());
                assert!(evaluation.previous_outputs.is_empty());
                assert_eq!(units.len(), 1);
                assert_eq!(units[0].record.durable_cursor, consumed);
                assert!(removals.is_empty());
                let roots = previous_calls.entry(call).or_default();
                assert!(roots.insert(units[0].record.clone()));
                assert_eq!(roots.len(), consumed as usize);
                let selected = units
                    .iter()
                    .flat_map(|unit| unit.support.iter().map(|support| &support.record))
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(
                    records
                        .iter()
                        .map(|record| &record.id)
                        .collect::<std::collections::BTreeSet<_>>(),
                    selected
                );
                let result = fixture.query.store().managed_result(
                    job.admitted(),
                    &reference.result_id,
                    u64::try_from(evaluation.context.time_utc_ns)?,
                    &fixture.control,
                )?;
                assert_eq!(result.result, *reference);
                let actual = evaluation_replay
                    .calls
                    .get(&call)
                    .ok_or("replayed Graph output")?
                    .output();
                let replayed = detector.evaluate(evaluation)?;
                assert_eq!(
                    araphor_analysis_sdk::wire::Output::encode(package, evaluation, &replayed)?,
                    araphor_analysis_sdk::wire::Output::encode(package, evaluation, actual)?,
                );
                let contribution = actual
                    .datasets
                    .iter()
                    .find(|data| data.name == "contributions")
                    .ok_or("current contributions")?;
                let contribution = algorithm::Contribution::decode(contribution)?;
                assert_eq!(contribution.len(), 1);
                assert_eq!(contribution[0].record, units[0].record);
                assert!(actual.checkpoint.is_none());
            }
            previous = Some(id);
        }
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 12);
        assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
        let mut next = Box::pin(stream.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 12);
        assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
        drop(next);
        Ok(())
    }
    .await;
    let joined = stream.cancel_and_join(&fixture.control).await;
    checked?;
    let _terminal = joined?;
    assert!(fixture
        .query
        .acquire_evaluation(fixture.source.tenant_id)
        .await
        .is_ok());
    Ok(())
}
