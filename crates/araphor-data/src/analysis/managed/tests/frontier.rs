use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn frontier_commits_with_receipt() -> TestResult {
    assert_frontier(true)?;
    assert_frontier(false)
}

fn assert_frontier(completed: bool) -> TestResult {
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
        pending: false,
        cursor: b"native-cursor".to_vec(),
        next_change: Some(30),
    });
    let mut invalid = input.clone();
    invalid.frontier.as_mut().ok_or("offered frontier")?.pending = true;
    let before = store.meta()?;
    assert!(matches!(
        store.register_managed_attempt(&captured, &invalid, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "managed attempt request",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
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
    let commit = ManagedCommit {
        completed,
        attempt: &attempt,
        now_utc_ns: 10,
        returns: &returns,
        selected: &selected,
        selected_schema: &fixture.model.outputs[0].schema,
    };
    let before = store.meta()?;
    assert!(matches!(
        store.commit_managed(&commit, || Err(
            Code::Denied.error("frontier final authority")
        )),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    let receipt = store.commit_managed(&commit, || Ok(()))?;
    let mut expected = input.frontier.clone();
    expected.as_mut().ok_or("offered frontier")?.pending = !completed;
    assert_eq!(receipt.frontier, expected);
    assert_eq!(receipt.results.len(), 2);
    let ManagedResume {
        instance: current,
        frontier,
        ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(frontier, expected);
    assert_eq!(attempt.request().time_utc_ns, 10);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let control = AnalysisReadControl::default();
    assert_eq!(
        store.managed_history(&current.grant.selection, "counter", &control)?,
        std::slice::from_ref(&receipt)
    );
    assert!(store
        .managed_selected([1; 16], "counter", &input.id, &control)?
        .is_some());
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
    {
        let mut writer = store.writer()?;
        let writer = writer.get_mut()?;
        let bytes: Vec<u8> = writer.query_row(
            "SELECT contract FROM managed_attempts WHERE attempt_id = ?",
            params![input.id],
            |row| row.get(0),
        )?;
        let mut attempt: super::super::model::Attempt = ManagedCodec::decode(&bytes)?;
        let frontier = attempt
            .receipt
            .as_mut()
            .and_then(|receipt| receipt.frontier.as_mut())
            .ok_or("saved frontier")?;
        if completed {
            frontier.cursor = b"foreign-cursor".to_vec();
        } else {
            frontier.next_change = Some(31);
        }
        writer.execute(
            "UPDATE managed_attempts SET contract = ? WHERE attempt_id = ?",
            params![ManagedCodec::encode(&attempt)?, input.id],
        )?;
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn pending_frontier_settles_startup() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let mut input = request("interrupted-frontier");
    input.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: b"native-cursor".to_vec(),
        next_change: None,
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
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
    store.recover()?;
    assert_eq!(store.meta()?, before);
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("live native intent")?;
    assert_eq!(
        ManagedCodec::encode(&loaded.0)?,
        ManagedCodec::encode(&attempt.0)?
    );
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert!(attempt
        .2
        .as_ref()
        .ok_or("live native claim")?
        .has_changed()
        .is_ok());
    drop(store);
    assert!(attempt
        .2
        .as_ref()
        .ok_or("closed native claim")?
        .has_changed()
        .is_err());
    let store = AnalysisStore::open(&root)?;
    let mut expected = before.clone();
    expected.commit_revision += 1;
    assert_eq!(store.meta()?, expected);
    assert_eq!(fixture.current(&store)?, fixture.instance);
    let terminal = ManagedTerminal {
        instance: "counter".into(),
        attempt: input.id.clone(),
        revision: expected.commit_revision,
        exit: ManagedExit::Cancelled,
        suspended: false,
    };
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("settled native intent")?;
    assert_eq!(loaded.request(), &input);
    assert_eq!(loaded.instance(), captured.instance());
    assert!(loaded.receipt().is_none());
    assert_eq!(loaded.terminal(), Some(&terminal));
    let mut saved = attempt.0.clone();
    saved.terminal = Some(terminal.clone());
    assert_eq!(
        ManagedCodec::encode(&loaded.0)?,
        ManagedCodec::encode(&saved)?
    );
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        ManagedResume {
            instance: fixture.instance.clone(),
            frontier: None,
            completed: terminal.revision
        }
    );
    let status = store.managed_status(
        &fixture.instance.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?;
    assert!(matches!(
        status.readiness,
        crate::PackageReadinessV1::Inactive
    ));
    assert_eq!(status.status_progress, 0);
    assert!(store
        .managed_selected(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let rows: (u64, u64) = store.read_snapshot(|reader| reader.query_row("SELECT (SELECT count(*) FROM analysis_results), (SELECT count(*) FROM managed_arrow)", [], |row| Ok((row.get(0)?, row.get(1)?))).context(crate::AnalysisDatabaseSnafu { operation: "read settled native output absence" }))?;
    assert_eq!(rows, (0, 0));
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Err(
            Code::Denied.error("startup terminal authority")
        )),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(
        store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?,
        terminal
    );
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Failed(Code::Incomplete), || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        store
            .register_managed_attempt(&captured, &input, || Ok(()))?
            .terminal(),
        Some(&terminal)
    );
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    for stale in [&attempt, &loaded] {
        let error = fixture
            .publish(&store, stale, &evaluations, &outputs)
            .err()
            .ok_or("settled native intent published")?;
        assert!(matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::AnalysisConflict { .. })
        ));
    }
    assert_eq!(store.meta()?, expected);
    assert_eq!(
        *store.subscribe_revision().borrow(),
        expected.commit_revision
    );
    store.verify_state()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, expected);
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .ok_or("clean-open native terminal")?
            .terminal(),
        Some(&terminal)
    );
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
                completed: false,
                attempt: &attempt,
                now_utc_ns: 10,
                returns: &returns,
                selected: &selected,
                selected_schema: &fixture.model.outputs[0].schema,
            },
            || Ok(())
        ),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "managed pending frontier",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    fixture.publish(&store, &attempt, &evaluations, &outputs)?;
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
        pending: false,
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
            pending: false,
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
