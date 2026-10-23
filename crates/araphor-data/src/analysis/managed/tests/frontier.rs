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
        ManagedResume {
            instance: fixture.instance.clone(),
            frontier: None,
            completed: 0
        }
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
            retained: None,
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
    let ManagedResume {
        instance: current,
        frontier,
        ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(frontier, input.frontier);
    assert_eq!(attempt.request().time_utc_ns, 10);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        ManagedResume {
            instance: current,
            frontier,
            completed: receipt.commit_revision
        }
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

#[test]
fn frontier_expiry_keeps_history() -> TestResult {
    for next_change in [None, Some(30)] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store");
        let store = AnalysisStore::open(&path)?;
        let fixture = Fixture::admit(&store)?;
        let captured = fixture.capture(&store, false)?;
        let mut input = request("timed-frontier");
        input.frontier = Some(ManagedFrontier {
            cursor: b"native-cursor".to_vec(),
            next_change,
        });
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        let receipt = fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        let control = AnalysisReadControl::default();
        let current = fixture.current(&store)?;
        assert!(!current.running);
        let reference = &receipt.results[&10];
        let ManagedOutput::Call {
            result: original, ..
        } = store.managed_output(&current, &reference.result_id, 29, &control)?
        else {
            return Err("package output variant".into());
        };
        assert!(original.current);
        let before = store.meta()?;
        for now in [29, 30, 31] {
            let expected = next_change.is_none_or(|deadline| now < deadline);
            for reference in receipt.results.values() {
                let ManagedOutput::Call { result, .. } =
                    store.managed_output(&current, &reference.result_id, now, &control)?
                else {
                    return Err("package output variant".into());
                };
                assert_eq!(result.current, expected);
            }
            let ManagedOutput::Call { result, .. } =
                store.managed_output(&current, &reference.result_id, now, &control)?
            else {
                return Err("package output variant".into());
            };
            assert_eq!(result.output, original.output);
            assert_eq!(result.context, original.context);
            assert_eq!(result.commit_revision, original.commit_revision);
            let mut reader = store.reader_until(&control)?;
            let fresh = control.run(&mut reader, |reader| {
                store.managed_current(
                    reader,
                    &current.spec,
                    &receipt.selected.result_id,
                    receipt.selected.commit_revision,
                    now,
                    &control,
                )
            })?;
            assert_eq!(fresh, expected);
        }
        assert_eq!(store.meta()?, before);
        assert_eq!(fixture.current(&store)?, current);
        assert_eq!(
            store.managed_history(&fixture.instance.grant.selection, "counter", &control)?,
            std::slice::from_ref(&receipt)
        );
        drop(store);
        let store = AnalysisStore::open(&path)?;
        assert_eq!(fixture.current(&store)?, current);
        assert_eq!(
            store.managed_history(&fixture.instance.grant.selection, "counter", &control)?,
            std::slice::from_ref(&receipt)
        );
        let ManagedOutput::Call { result, .. } =
            store.managed_output(&current, &reference.result_id, 31, &control)?
        else {
            return Err("package output variant".into());
        };
        assert_eq!(result.current, next_change.is_none());
        assert_eq!(
            store
                .managed_attempt([1; 16], "counter", &input.id, &control)?
                .ok_or("reopened timed attempt")?
                .request(),
            &input
        );
        assert_eq!(store.meta()?, before);
    }
    Ok(())
}
