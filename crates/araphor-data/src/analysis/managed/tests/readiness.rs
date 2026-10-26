use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn failed_frontier_keeps_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let mut input = request("known-failure");
    input.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: vec![1, 2, 3],
        next_change: Some(99),
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let terminal = store.finish_managed(&attempt, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    let resumed = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(resumed.instance, fixture.instance);
    assert_eq!(resumed.instance.progress, 0);
    assert_eq!(resumed.frontier, input.frontier);
    assert_eq!(resumed.completed, terminal.revision);
    assert_eq!(attempt.request(), &input);
    assert!(store
        .managed_selected(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let before = store.meta()?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        resumed
    );
    assert_eq!(store.meta()?, before);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        resumed
    );
    let saved = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("failed attempt")?;
    assert_eq!(saved.request(), &input);
    assert_eq!(saved.terminal(), Some(&terminal));
    assert!(saved.receipt().is_none());
    Ok(())
}

#[test]
fn cancelled_frontier_is_unconsumed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let resumed = {
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = Fixture::admit(&store)?;
        let captured = fixture.capture(&store, false)?;
        let mut first = request("successful");
        first.frontier = Some(ManagedFrontier {
            pending: false,
            cursor: vec![1],
            next_change: Some(50),
        });
        let attempt = store.register_managed_attempt(&captured, &first, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&first, 10, Some(&captured))?,
            fixture.evaluation(&first, 11, Some(&captured))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let captured = fixture.capture(&store, false)?;
        let mut input = request("cancelled");
        input.frontier = Some(ManagedFrontier {
            pending: false,
            cursor: vec![2],
            next_change: Some(75),
        });
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
        let resumed = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
        assert_eq!(resumed.instance.progress, receipt.commit_revision);
        assert_eq!(resumed.frontier, first.frontier);
        assert_ne!(resumed.frontier, input.frontier);
        assert_eq!(resumed.completed, terminal.revision);
        assert_eq!(attempt.request(), &input);
        assert!(store
            .managed_selected(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .is_none());
        assert!(store
            .managed_selected(
                [1; 16],
                "counter",
                &first.id,
                &AnalysisReadControl::default()
            )?
            .is_some());
        resumed
    };
    let store = AnalysisStore::open(directory.path().join("store"))?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        resumed
    );
    Ok(())
}

#[test]
fn completion_fences_capture() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let resumed = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    let captured = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&captured, &request("finished"), || Ok(()))?;
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let requests = AnalysisTableRequests::new();
    let before = store.meta()?;
    let selected = ManagedRead {
        expected: None,
        instance: resumed.instance.clone(),
        rebuild: false,
        completed: Some(resumed.completed),
    };
    let error = store
        .read_managed_tables(
            &resumed.instance.grant.selection,
            &selected,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .err()
        .ok_or("stale completion captured")?;
    assert!(matches!(
        error,
        crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture completion",
            ..
        }
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn completion_fences_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&captured, &request("finished"), || Ok(()))?;
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let before = store.meta()?;
    let input = request("stale-registration");
    assert!(matches!(
        store.register_managed_attempt(&captured, &input, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn completion_fences_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("stale-publication");
    let stale = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let finished = store.register_managed_attempt(&captured, &request("finished"), || Ok(()))?;
    store.finish_managed(&finished, ManagedExit::Cancelled, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let before = store.meta()?;
    let error = fixture
        .publish(&store, &stale, &evaluations, &outputs)
        .err()
        .ok_or("stale publication succeeded")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store
            .managed_instance([1; 16], "counter", &AnalysisReadControl::default())?
            .ok_or("instance")?
            .progress,
        0
    );
    assert!(store
        .managed_selected(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    Ok(())
}

#[test]
fn failed_frontier_can_resume() -> TestResult {
    for code in [Code::Incomplete, Code::Limit] {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = Fixture::admit(&store)?;
        let captured = fixture.capture(&store, false)?;
        let mut input = request("pressure-or-bound");
        input.frontier = Some(ManagedFrontier {
            pending: false,
            cursor: vec![1],
            next_change: None,
        });
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let terminal = store.finish_managed(&attempt, ManagedExit::Failed(code), || Ok(()))?;
        let before = store.meta()?;
        let resumed = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
        assert_eq!(resumed.frontier, input.frontier);
        assert_eq!(resumed.completed, terminal.revision);
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store
                .managed_instance([1; 16], "counter", &AnalysisReadControl::default())?
                .ok_or("instance")?
                .progress,
            0
        );
    }
    Ok(())
}

#[test]
fn completion_recovery_rejects_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let capture = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&capture, &request("finished"), || Ok(()))?;
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let capture = fixture.capture(&store, false)?;
    assert!(capture.contract.completed > 0);
    let attempt = store.register_managed_attempt(&capture, &request("corrupt"), || Ok(()))?;
    let mut saved = attempt.0.clone();
    saved.capture.completed = 0;
    let mut writer = store.writer()?;
    writer.get_mut()?.execute(
        "UPDATE managed_attempts SET contract = ? WHERE attempt_id = 'corrupt'",
        params![serde_json::to_vec(&saved)?],
    )?;
    drop(writer);
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}
