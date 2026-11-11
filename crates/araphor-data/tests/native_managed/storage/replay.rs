use super::calls::call_context;
use super::StorageFixture as Fixture;
use super::*;
use araphor_data::{AnalysisExtractLimits, AnalysisReadModeV1, AnalysisStore, AnalysisTableRead};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "replay/corruption.rs"]
mod corruption;
#[path = "replay/trace.rs"]
mod trace;

fn fixture(store: &AnalysisStore, extra: bool) -> TestResult<Fixture> {
    Fixture::new_model(
        store,
        "counter",
        "Retain independent call state.".into(),
        AnalysisSelectionV1::new([1; 16], Vec::new()),
        extra,
    )
}

#[test]
fn references_require_no_payloads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store, true)?;
    let captured = fixture.capture(&store)?;
    let request = request("reference");
    let attempt = store.register_managed_attempt(&captured, &request, || Ok(()))?;
    let evaluations = [
        fixture.continued(&request, 10, Some(&captured))?,
        fixture.continued(&request, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    let before = store.meta()?;
    for (id, expected) in receipt
        .results
        .iter()
        .map(|(call, reference)| (reference.result_id.as_str(), Some(*call)))
        .chain(std::iter::once((receipt.selected.result_id.as_str(), None)))
    {
        let (reference, call, _) = store.managed_reference(&current, id, 10, &control)?;
        assert_eq!(call, expected);
        assert_eq!(reference.request(), &request);
        assert_eq!(reference.receipt(), Some(&receipt));
        assert_eq!(reference.captured_revision(), captured.revision());
        assert_eq!(reference.instance().spec, current.spec);
        let mut foreign = current.clone();
        foreign.spec.id = "another-instance".into();
        assert!(store.managed_reference(&foreign, id, 10, &control).is_err());
    }
    assert_eq!(store.meta()?, before);
    control.cancel()?;
    assert!(store
        .managed_reference(&current, &receipt.selected.result_id, 10, &control)
        .is_err());
    Ok(())
}

#[test]
fn references_keep_input_metadata() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store, true)?;
    let mut saved = Vec::new();
    for (index, id) in ["initial", "continued", "rebuild", "parameters"]
        .into_iter()
        .enumerate()
    {
        let mut captured = fixture.capture_rebuild(&store, index == 2)?;
        for call in [10, 11] {
            if captured.prior(call).is_some() {
                captured.hydrate_prior(
                    call,
                    &fixture.model,
                    Some(sdk::Dataset {
                        name: "parameters".into(),
                        batches: vec![Fixture::batch(
                            &fixture.model.parameters,
                            if call == 10 { 2 } else { 3 },
                        )?],
                    }),
                    None,
                )?;
            }
        }
        let mut input = request(id);
        input.rebuild = index == 2;
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let mut evaluations = [
            fixture.continued(&input, 10, Some(&captured))?,
            fixture.continued(&input, 11, Some(&captured))?,
        ];
        if index == 0 {
            evaluations[0].inputs.reverse();
            let source = evaluations[0]
                .inputs
                .iter_mut()
                .find(|input| input.data.name == "source")
                .ok_or("source input")?;
            let batch = source.data.batches[0].clone();
            source.data.batches = vec![
                sdk::RecordBatch::new_empty(batch.schema()),
                batch.clone(),
                sdk::RecordBatch::new_empty(batch.schema()),
            ];
            source.revision.window = Some(sdk::SourceWindow {
                source: vec![1, 2, 3],
                start_utc_ns: 1,
                end_utc_ns: 9,
            });
            source.coverage = sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["fixture gap".into()],
            };
            evaluations[1].inputs[1].data.batches = vec![sdk::RecordBatch::new_empty(Arc::new(
                fixture.model.inputs[1].port.schema.clone(),
            ))];
        }
        if index == 3 {
            evaluations[0].parameters = Some(Fixture::batch(&fixture.model.parameters, 9)?);
            evaluations[0].checkpoint = None;
        }
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let current = fixture.current(&store)?;
        for (call, expected) in [10, 11].into_iter().zip(evaluations) {
            let reference = receipt.results[&call].clone();
            let actual = store.managed_result(
                &current,
                &reference.result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert!(
                matches!(&actual.kind, araphor_data::InstanceResultKindV1::Call { call: id, .. } if *id == call)
            );
            assert_eq!(actual.generation, current.generation);
            assert_eq!(actual.source.commit_revision, captured.revision());
            assert_eq!(call_context(&actual)?.context, expected.context);
            assert!(call_context(&actual)?.matches(&expected.inputs));
            saved.push(actual);
        }
    }
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let current = fixture.current(&store)?;
    for mut expected in saved {
        let actual = store.managed_result(
            &current,
            &expected.result.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        expected.current = expected.receipt.commit_revision == current.progress;
        assert_eq!(
            serde_json::to_value(&actual)?,
            serde_json::to_value(&expected)?
        );
        let mut foreign = current.clone();
        foreign.spec.id = "another-instance".into();
        assert!(store
            .managed_result(
                &foreign,
                &expected.result.result_id,
                10,
                &AnalysisReadControl::default()
            )
            .is_err());
        foreign.spec.tenant = [2; 16];
        assert!(store
            .managed_result(
                &foreign,
                &expected.result.result_id,
                10,
                &AnalysisReadControl::default()
            )
            .is_err());
    }
    assert_eq!(store.meta()?.commit_revision, before.commit_revision);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.managed_result(&current, "absent", 10, &cancelled),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn call_references_commit_atomically() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store, false)?;
    let captured = fixture.capture(&store)?;
    let input = request("atomic-input");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let before = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    let pending = records(store.view()?.as_ref(), b"\0data/a")?;
    let mut checked = false;
    assert!(fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            checked = true;
            Err(Code::Denied.error("saved input final authority"))
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(records(store.view()?.as_ref(), b"\0data/a")?, pending);
    assert!(records(store.view()?.as_ref(), b"\0data/X")?.is_empty());
    assert!(records(store.view()?.as_ref(), b"\0data/U")?.is_empty());
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    for (call, expected) in [10, 11].into_iter().zip(evaluations) {
        let actual = store.managed_result(
            &current,
            &receipt.results[&call].result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(call_context(&actual)?.context, expected.context);
        assert_eq!(actual.result, receipt.results[&call]);
        assert_eq!(
            fixture.checkpoint(&store, &actual.result)?.datasets[0].batches,
            outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("declared checkpoint")?
                .datasets[0]
                .batches,
        );
    }
    Ok(())
}
