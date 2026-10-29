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
            (
                Vec<algorithm::Observation>,
                Vec<algorithm::Fact>,
                araphor_analysis_sdk::Revision,
                araphor_analysis_sdk::Output,
                Vec<araphor_analysis_sdk::Dataset>,
            ),
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
                let evaluation = fixture.query.store().managed_evaluation(
                    job.admitted(),
                    &reference.result_id,
                    &fixture.control,
                )?;
                let records_input = evaluation.input("records")?;
                let records = algorithm::Observation::decode(&records_input.data)?;
                let facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
                assert_eq!(records.len(), consumed as usize);
                if let Some((old_records, old_facts, revision, output, full)) =
                    previous_calls.get(&call)
                {
                    assert_eq!(&records[..old_records.len()], old_records);
                    assert_eq!(&facts[..old_facts.len()], old_facts);
                    assert_ne!(&records_input.revision, revision);
                    assert_eq!(evaluation.previous_outputs.len(), full.len());
                    for (actual, expected) in evaluation.previous_outputs.iter().zip(full) {
                        assert_eq!(actual.name, expected.name);
                        assert_eq!(actual.batches, expected.batches);
                    }
                    let checkpoint = evaluation.checkpoint.as_ref().ok_or("prior checkpoint")?;
                    let saved_checkpoint = output.checkpoint.as_ref().ok_or("saved checkpoint")?;
                    assert_eq!(checkpoint.version, saved_checkpoint.version);
                    assert_eq!(checkpoint.datasets.len(), saved_checkpoint.datasets.len());
                    for (actual, expected) in
                        checkpoint.datasets.iter().zip(&saved_checkpoint.datasets)
                    {
                        assert_eq!(actual.name, expected.name);
                        assert_eq!(actual.batches, expected.batches);
                    }
                    let progress = evaluation
                        .previous_outputs
                        .iter()
                        .find(|data| data.name == "progress")
                        .ok_or("prior progress")?;
                    assert_eq!(
                        algorithm::Progress::decode(progress)?
                            .into_iter()
                            .map(|row| row.record)
                            .collect::<Vec<_>>(),
                        old_records
                            .iter()
                            .map(|record| record.id.clone())
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(
                        progress
                            .batches
                            .iter()
                            .map(|batch| batch.num_rows())
                            .sum::<usize>(),
                        consumed as usize - 1
                    );
                } else {
                    assert_eq!(consumed, 1);
                    assert!(evaluation.previous_outputs.is_empty());
                    assert!(evaluation.checkpoint.is_none());
                }
                let result = fixture.query.store().managed_result(
                    job.admitted(),
                    &reference.result_id,
                    u64::try_from(evaluation.context.time_utc_ns)?,
                    &fixture.control,
                )?;
                let replayed = detector.evaluate(&evaluation)?;
                assert_eq!(
                    araphor_analysis_sdk::wire::Output::encode(package, &evaluation, &replayed)?,
                    araphor_analysis_sdk::wire::Output::encode(
                        package,
                        &evaluation,
                        &result.output
                    )?
                );
                let progress = result
                    .output
                    .datasets
                    .iter()
                    .find(|data| data.name == "progress")
                    .ok_or("current progress")?;
                let mut folded = evaluation
                    .previous_outputs
                    .iter()
                    .find(|data| data.name == "progress")
                    .map(algorithm::Progress::decode)
                    .transpose()?
                    .unwrap_or_default();
                let additions = algorithm::Progress::decode(progress)?;
                assert_eq!(additions.len(), 1);
                assert_eq!(
                    additions[0].record,
                    records.last().ok_or("current Graph record")?.id
                );
                assert!(algorithm::ProgressRemoval::decode(
                    result
                        .output
                        .datasets
                        .iter()
                        .find(|data| data.name == "progress_removals")
                        .ok_or("current progress removals")?
                )?
                .is_empty());
                folded.extend(additions);
                folded.sort_by(|left, right| left.record.cmp(&right.record));
                assert_eq!(
                    folded.into_iter().map(|row| row.record).collect::<Vec<_>>(),
                    records
                        .iter()
                        .map(|record| record.id.clone())
                        .collect::<Vec<_>>()
                );
                let mut fresh = evaluation.clone();
                fresh.checkpoint = None;
                fresh.previous_outputs.clear();
                let mut full = detector.evaluate(&fresh)?.datasets;
                let findings = full
                    .iter_mut()
                    .find(|data| data.name == "findings")
                    .ok_or("complete Graph findings")?;
                let mut rows = algorithm::FindingChange::decode(findings)?;
                for row in &mut rows {
                    row.prior_reason = Some(algorithm::FindingReasonV1::from_analysis_code(
                        &package.id,
                        &row.reason_code,
                    )?);
                }
                *findings = algorithm::FindingChange::encode(&rows)?;
                previous_calls.insert(
                    call,
                    (
                        records,
                        facts,
                        records_input.revision.clone(),
                        result.output,
                        full,
                    ),
                );
            }
            previous = Some(id);
        }
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
        assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
        let mut next = Box::pin(stream.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
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
