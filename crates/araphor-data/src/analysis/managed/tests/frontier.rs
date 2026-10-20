use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn frontier_commits_with_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        (fixture.instance.clone(), None)
    );
    let captured = fixture.capture(&store, false)?;
    let mut input = request("frontier");
    input.frontier = Some(ManagedFrontier {
        cursor: b"native-cursor".to_vec(),
        next_change: Some(30),
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let returns = evaluations
        .iter()
        .zip(&outputs)
        .enumerate()
        .map(|(index, (evaluation, output))| ManagedReturn {
            call: 10 + index as u64,
            evaluation,
            output,
        })
        .collect::<Vec<_>>();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    let before = store.meta()?;
    assert!(matches!(
        store.commit_managed(
            &ManagedCommit {
                attempt: &attempt,
                now_utc_ns: 10,
                returns: &returns,
                selected: &selected,
                selected_schema: &fixture.model.outputs[0].schema,
                selected_limits: fixture.model.limits,
            },
            || Err(Code::Denied.error("frontier final authority"))
        ),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(receipt.frontier, input.frontier);
    assert_eq!(receipt.results.len(), 2);
    let (current, frontier) =
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(frontier, input.frontier);
    assert_eq!(attempt.request().time_utc_ns, 10);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        (current, frontier)
    );
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .ok_or("completed frontier attempt")?
            .receipt(),
        Some(&receipt)
    );
    Ok(())
}

#[test]
fn pending_frontier_blocks_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let mut input = request("interrupted-frontier");
    input.frontier = Some(ManagedFrontier {
        cursor: b"native-cursor".to_vec(),
        next_change: None,
    });
    store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let mut other = input.clone();
    other.id = "replacement-is-forbidden".into();
    assert!(matches!(
        store.register_managed_attempt(&captured, &other, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert!(store
        .managed_attempt(
            [1; 16],
            "counter",
            &other.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?.progress, 0);
    Ok(())
}

#[test]
fn finite_result_rejects_resume() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("finite");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed native frontier unavailable",
            ..
        })
    ));
    Ok(())
}

#[test]
fn frontier_rejects_corrupt_completion() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let mut input = request("corrupt-completion");
    input.frontier = Some(ManagedFrontier {
        cursor: b"native-cursor".to_vec(),
        next_change: None,
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    {
        let mut writer = store.writer()?;
        writer
            .get_mut()?
            .execute("UPDATE managed_attempts SET completed = 0", [])?;
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}
