use super::notices::next_receipt;
use super::*;
use crate::graph::tests::fixture::{record, wire};

#[tokio::test]
async fn empty_gate_keeps_history() -> TestResult {
    let records = (1..=3)
        .map(|cursor| {
            record(
                cursor,
                &wire(
                    cursor,
                    erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
                    2,
                    2,
                    [20; 16],
                ),
            )
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let fixture = Fixture::with_records(Target::Wasm, records)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "empty-history",
            "SELECT * FROM events WHERE (SELECT COUNT(*) FROM events) = 3",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let outcome: TestResult = async {
        let first = next_receipt(&mut stream).await?;
        assert_eq!(first.results.len(), 3);
        let data = fixture.query.store();
        let current = data
            .managed_instance(fixture.source.tenant_id, "empty-history", &fixture.control)?
            .ok_or("initial Graph instance")?;
        let now = request("inspect-history")?.time_utc_ns;
        let requests = araphor_data::AnalysisTableRequests::new();
        let capture = |current| {
            data.read_managed_tables(
                &grant.selection,
                &araphor_data::ManagedRead {
                    execution: None,
                    instance: current,
                    expected: None,
                    completed: None,
                    rebuild: false,
                    follow: false,
                },
                araphor_data::AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    inputs: None,
                    mode: araphor_data::AnalysisReadModeV1::Complete,
                    now,
                },
                araphor_data::AnalysisExtractLimits::default(),
                &fixture.control,
            )
        };
        let captured_revision = araphor_query::follow::Cursor::decode(
            &first.frontier.as_ref().ok_or("initial Graph frontier")?.cursor,
        )?
        .read_revision();
        assert!(captured_revision < first.commit_revision);
        let captured = capture(current.clone())?;
        let mut saved = BTreeMap::new();
        for (call, reference) in &first.results {
            let prior = captured.state.prior(*call).ok_or("initial call head")?;
            assert_eq!(
                (&prior.result, prior.revision),
                (&reference.result_id, reference.commit_revision)
            );
            let araphor_data::ManagedOutput::Call { result, .. } =
                data.managed_output(&current, &reference.result_id, now, &fixture.control)?
            else {
                return Err("initial Graph call".into());
            };
            assert!(!result.current);
            saved.insert(
                *call,
                (result.context, result.output, result.commit_revision),
            );
        }
        drop(captured);
        let fourth = record(
            4,
            &wire(
                4,
                erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
                2,
                2,
                [20; 16],
            ),
        )?;
        assert_eq!(fourth.id.stream, fixture.source);
        data.accept_validated_batch(
            fixture.source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: fourth.id.cpu_id,
                first_cursor: 4,
                last_cursor: 4,
                intake_utc_ns: 4,
                frame_ends: vec![fourth.wire_record.len()],
                framed_records: fourth.wire_record.into(),
            },
        )?;
        let empty = next_receipt(&mut stream).await?;
        assert!(empty.results.is_empty());
        assert!(empty.commit_revision > first.commit_revision);
        let current = data
            .managed_instance(fixture.source.tenant_id, "empty-history", &fixture.control)?
            .ok_or("empty Graph instance")?;
        assert_eq!(current.progress, empty.commit_revision);
        let captured = capture(current.clone())?;
        for (call, reference) in &first.results {
            let prior = captured.state.prior(*call).ok_or("retained call head")?;
            assert_eq!(
                (&prior.result, prior.revision),
                (&reference.result_id, reference.commit_revision)
            );
            let araphor_data::ManagedOutput::Call { result, .. } =
                data.managed_output(&current, &reference.result_id, now, &fixture.control)?
            else {
                return Err("historical Graph call".into());
            };
            assert!(!result.current);
            assert_eq!(
                (result.context, result.output, result.commit_revision),
                saved[call]
            );
        }
        data.fault_write(
            "UPDATE analysis_results SET request_meta = 'invalid'::BLOB WHERE tenant_id = ? AND result_id = ?",
            &[&fixture.source.tenant_id.as_slice(), &empty.selected.result_id],
        )?;
        let reference = first.results.values().next().ok_or("historical call")?;
        assert!(data
            .managed_output(&current, &reference.result_id, now, &fixture.control)
            .is_err());
        Ok(())
    }
    .await;
    stream.cancel_and_join(&fixture.control).await?;
    outcome
}

#[tokio::test]
async fn failed_graph_disables_reuse() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(&grant, &definition, "failed-reuse", "SELECT * FROM events")
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let first = next_receipt(&mut stream).await;
    stream.cancel_and_join(&fixture.control).await?;
    let first = first?;
    let store = fixture.query.store();
    let resume =
        store.managed_resume(fixture.source.tenant_id, "failed-reuse", &fixture.control)?;
    let requests = araphor_data::AnalysisTableRequests::new();
    let now = request("capture-reuse")?.time_utc_ns;
    let capture = |instance: araphor_data::ManagedInstance| {
        store.read_managed_tables(
            &grant.selection,
            &araphor_data::ManagedRead {
                execution: None,
                instance,
                expected: None,
                completed: Some(resume.completed),
                rebuild: false,
                follow: false,
            },
            araphor_data::AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: araphor_data::AnalysisReadModeV1::Complete,
                now,
            },
            araphor_data::AnalysisExtractLimits::default(),
            &fixture.control,
        )
    };
    let before = capture(resume.instance.clone())?;
    assert_eq!(first.results.len(), 3);
    for call in first.results.keys() {
        let prior = before.state.prior(*call).ok_or("saved Graph call")?;
        assert!(prior.reusable);
        assert!(prior.retained.is_some());
    }
    drop(before);
    let failed = store.fail_managed(&resume, Code::Limit, || Ok(()))?;
    let captured = capture(failed.clone())?;
    for (call, reference) in &first.results {
        let prior = captured
            .state
            .prior(*call)
            .ok_or("failed Graph saved call")?;
        assert_eq!(
            (&prior.result, prior.revision),
            (&reference.result_id, reference.commit_revision)
        );
        assert!(!prior.reusable);
        let retained = prior.retained.as_ref().ok_or("continued Graph call")?;
        let declaration = &failed.spec.manifest.calls[call];
        let descriptor = Detector::from_id(&declaration.package.package_id)?.descriptor();
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == retained.evaluation.export)
            .ok_or("retained Graph model")?;
        let mut evaluation = retained.evaluation.clone();
        let (checkpoint, previous_outputs) = prior.state_sparse(
            model,
            &evaluation.inputs,
            evaluation.parameters.as_ref(),
            false,
            true,
        )?;
        assert!(checkpoint.is_some());
        assert_eq!(previous_outputs.len(), model.outputs.len());
        assert_eq!(
            araphor_analysis_builtins::graph::Resume::basis(
                checkpoint.as_ref().ok_or("Graph checkpoint")?
            )?,
            araphor_analysis_builtins::graph::ResumeBasis::Progress
        );
        let progress = previous_outputs
            .iter()
            .find(|data| data.name == "progress")
            .ok_or("normalized Graph progress")?;
        assert!(!araphor_analysis_builtins::graph::Progress::decode(progress)?.is_empty());
        assert!(previous_outputs
            .iter()
            .filter(|data| data.name != "progress")
            .all(|data| data.rows() == 0));
        evaluation.checkpoint = checkpoint;
        evaluation.previous_outputs = previous_outputs;
        let encoded = descriptor.check_evaluation(&evaluation)?.encode()?;
        let resumed = encoded.decode(&descriptor)?;
        assert_eq!(
            araphor_analysis_builtins::graph::Resume::basis(
                resumed
                    .checkpoint
                    .as_ref()
                    .ok_or("decoded Graph checkpoint")?
            )?,
            araphor_analysis_builtins::graph::ResumeBasis::Progress
        );
        let expected = sdk::wire::Output::encode_model(&retained.output, model)?;
        let delta = Detector::from_id(&descriptor.id)?.evaluate(&resumed)?;
        let actual = sdk::wire::Output::encode_model(&delta, model)?;
        assert_eq!(actual.checkpoint, expected.checkpoint);
        assert!(delta.datasets.iter().all(|data| data.rows() == 0));
        assert!(delta.reasons.is_empty());
    }
    store.stop_managed(&failed, || Ok(()))?;
    Ok(())
}
